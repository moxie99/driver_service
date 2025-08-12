import { Response, Request } from 'express'
import Category, { ICategory } from '../models/category.model'
import { ApiResponse } from '../types'

export const getCategories = async (
  req: Request,
  res: Response
): Promise<Response> => {
  try {
    const categories = await Category.find()
    if (categories.length === 0) {
      return res.status(404).json({
        statusCode: '05',
        error: 'No categories found',
      } as ApiResponse)
    }
    return res.status(200).json({
      statusCode: '00',
      data: categories.map((cat: ICategory) => ({
        id: cat._id,
        name: cat.name,
        description: cat.description,
      })),
    } as ApiResponse)
  } catch (error) {
    return res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during category retrieval',
    } as ApiResponse)
  }
}

export const addCategory = async (
  req: Request,
  res: Response
): Promise<Response> => {
  try {
    const { name, description } = req.body
    const existingCategory = await Category.findOne({ name })
    if (existingCategory) {
      return res.status(400).json({
        statusCode: '01',
        error: 'Category already exists',
      } as ApiResponse)
    }
    const category = new Category({ name, description })
    await category.save()
    return res.status(201).json({
      statusCode: '00',
      message: 'Category added successfully',
      data: {
        id: category._id,
        name: category.name,
        description: category.description,
      },
    } as ApiResponse)
  } catch (error) {
    return res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during category addition',
    } as ApiResponse)
  }
}
