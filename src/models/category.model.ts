import mongoose, { Schema, Document, Model } from 'mongoose'

export interface ICategory extends Document {
  name: string
  description: string
}

const categorySchema = new Schema<ICategory>(
  {
    name: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true, // removes leading/trailing spaces
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
  },
  { timestamps: true }
)

// Avoid model overwrite issues in dev/hot-reload
const Category: Model<ICategory> =
  mongoose.models.Category ||
  mongoose.model<ICategory>('Category', categorySchema)

export default Category
