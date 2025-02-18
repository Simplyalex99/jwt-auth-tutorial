import express, { Express, Request, Response, NextFunction } from 'express'
import cookieParser from 'cookie-parser'
import 'dotenv/config'
import { createClient } from 'redis'
import jwt, { JwtPayload } from 'jsonwebtoken'

if (process.env.REFRESH_TOKEN_SECRET === undefined) {
  throw new Error('Refresh token secret not defined')
}
if (process.env.ACCESS_TOKEN_SECRET === undefined) {
  throw new Error('Access token secret not defined')
}
if (process.env.REDIS_URL === undefined) {
  throw new Error('Redis not defined')
}

const REDIS_URL = process.env.REDIS_URL
const redisClient = createClient({
  url: REDIS_URL,
})

redisClient.on('error', (err) => {
  console.error('Redis Client Error:', err)
})
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET
const refreshTokenExpiresAt = 86400 * 14 // 14 days (1209600 seconds)
const accessTokenExpiresAt = 60 * 15 // 15 minutes (900 seconds)
const refreshKey = 'refreshToken' // cookie key for refresh token
const accessKey = 'accessToken' // cookie key for access token
const app: Express = express()

app.use(express.json())
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }))
app.post(
  '/v1/sign-in',
  (
    req: Request<object, object, { email: string; role: string }>,
    res: Response
  ) => {
    const payload = req.body
    if (payload === undefined) {
      res.status(400).send()
      return
    }
    const accessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, {
      expiresIn: accessTokenExpiresAt,
    })
    const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET, {
      expiresIn: refreshTokenExpiresAt,
    })

    res.cookie(refreshKey, refreshToken, {
      expires: new Date(Date.now() + refreshTokenExpiresAt * 1000),
      httpOnly: true,
      secure: true,
      path: '/refresh',
      sameSite: 'strict',
    })

    res.status(200).json({ accessToken })
  }
)

app.use(
  '/v1/protected',
  (
    req: Request<object, object, { email: string; role: string }>,
    res: Response,
    next: NextFunction
  ) => {
    try {
      const authHeader = req.headers.authorization
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Unauthorized: No token provided' })
        return
      }

      const accessToken = authHeader.split(' ')[1] // Extract tokens after 'Bearer '
      jwt.verify(accessToken, ACCESS_TOKEN_SECRET) //checks expiration date also
      next()
    } catch (err) {
      res.status(401).send()
    }
  }
)

app.post(
  '/v1/refresh',
  (
    req: Request<object, object, { email: string; role: string }>,
    res: Response
  ) => {
    try {
      const cookies = req?.cookies
      const payload = req.body
      if (!cookies) {
        res.status(401).send()
        return
      }
      if (payload === undefined) {
        res.status(400).send()
        return
      }
      const refreshToken = cookies[refreshKey]
      if (refreshToken === null) {
        res.status(401).send()
        return
      }
      jwt.verify(refreshToken, REFRESH_TOKEN_SECRET)
      const newAccessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, {
        expiresIn: accessTokenExpiresAt,
      })
      const newRefreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET, {
        expiresIn: refreshTokenExpiresAt,
      })
      res.clearCookie(refreshKey, {
        maxAge: 0,
      })
      res.cookie(refreshKey, newRefreshToken, {
        expires: new Date(Date.now() + refreshTokenExpiresAt * 1000),
        httpOnly: true,
        secure: true,
        path: '/refresh',
        sameSite: 'strict',
      })
      res.status(200).json({ accessToken: newAccessToken })
    } catch (err) {
      res.status(401).send()
    }
  }
)
app.post('/v1/sign-out', (req: Request, res: Response) => {
  const cookies = req?.cookies
  if (!cookies) {
    res.status(401).send()
    return
  }
  const refreshToken = cookies[refreshKey]
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).send()
    return
  }

  const accessToken = authHeader.split('')[1]
  redisClient.set(accessToken, 'blacklist', { EX: accessTokenExpiresAt })
  redisClient.set(refreshToken, 'blacklist', { EX: refreshTokenExpiresAt })
  /**
   * /refresh /protected /sign-out
   * jwt.verify(token,TOKEN_SECRET) // for access and refresh token
   * const tokenIsExpired = redisClient.get(token)
   * if(tokenIsExpired !===null){
   *  res.status(401).send()
   * }
   *
   */
})

const port = 3000
app.listen(port, () => {
  console.log(`Listening on ${port}`)
})
