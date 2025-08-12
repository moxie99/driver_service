import { Router } from 'express'
import { body } from 'express-validator'
import { getCategories, addCategory } from '../controllers/category.controller'
import { authenticate } from '../middleware/auth.middleware'
import { validateRequest } from '../middleware/validate.middleware'

const router = Router()

router.get('/categories', getCategories)

router.post(
  '/categories',
  authenticate,
  [
    body('name').notEmpty().withMessage('Category name is required'),
    body('description')
      .notEmpty()
      .withMessage('Category description is required'),
  ],
  validateRequest,
  addCategory
)

export default router
