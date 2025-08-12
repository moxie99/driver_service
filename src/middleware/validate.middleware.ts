import { Request, Response, NextFunction } from 'express'
import { validationResult } from 'express-validator'
import { ApiResponse } from '../types'

export const validateRequest = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.status(400).json({
      statusCode: '01',
      error: 'Validation failed',
      errors: errors.array().map((err) => err.msg),
    } as ApiResponse)
  }
  next()
}
