import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { ApiResponse } from '../types'

export interface AuthRequest extends Request {
  userId?: string
  role?: string
}

export const authenticate = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const token = req.header('Authorization')?.replace('Bearer ', '')
  if (!token) {
    return res.status(401).json({
      statusCode: '04',
      error: 'Access denied, no token provided',
    } as ApiResponse)
  }
  try {
    const decoded = jwt.verify(token, 'your_jwt_secret') as {
      userId: string
      role: string
    }
    req.userId = decoded.userId
    req.role = decoded.role
    next()
  } catch (error) {
    res
      .status(401)
      .json({ statusCode: '04', error: 'Invalid token' } as ApiResponse)
  }
}
