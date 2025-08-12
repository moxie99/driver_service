import mongoose from 'mongoose'
import dotenv from 'dotenv'
import Category from './src/models/category.model'
dotenv.config() // Load .env variables

const categories = [
  {
    name: 'POP',
    description: 'Plaster of Paris for interior decoration and molds',
  },
  {
    name: 'Cement',
    description: 'Portland cement for concrete and structural works',
  },
  {
    name: 'Gypsum Plaster',
    description: 'Lightweight plaster for walls and ceilings',
  },
  {
    name: 'Lime Plaster',
    description: 'Calcium hydroxide-based plaster for frescoes',
  },
  {
    name: 'Iron Rods',
    description: 'Steel reinforcement bars for concrete structures',
  },
  { name: 'Steel Beams', description: 'Structural steel for frameworks' },
  {
    name: 'Steel Plates',
    description: 'Steel plates for construction and manufacturing',
  },
  {
    name: 'Aluminum Pipes',
    description: 'Lightweight pipes for plumbing and industrial use',
  },
  {
    name: 'Copper Pipes',
    description: 'Pipes for plumbing and electrical applications',
  },
  {
    name: 'Sand',
    description: 'Natural or manufactured sand for concrete and mortar',
  },
  { name: 'Gravel', description: 'Aggregate for concrete and road base' },
  { name: 'Crushed Stone', description: 'Stone aggregate for construction' },
  { name: 'Limestone', description: 'Raw material for cement and aggregates' },
  { name: 'Clay Bricks', description: 'Fired or unfired bricks for masonry' },
  { name: 'Concrete Blocks', description: 'Cement-based blocks for walls' },
  {
    name: 'Fly Ash Bricks',
    description: 'Eco-friendly bricks from coal byproducts',
  },
  { name: 'Asphalt', description: 'Material for road paving and roofing' },
  { name: 'Timber', description: 'Wood for structural framing' },
  { name: 'Ceramic Tiles', description: 'Tiles for flooring and walls' },
  {
    name: 'Paints',
    description: 'High-volume paint containers for construction',
  },
  { name: 'Glass Sheets', description: 'Glass for windows and facades' },
  { name: 'Iron Ore', description: 'Raw material for steel production' },
  { name: 'Coal', description: 'Fuel for energy and steel manufacturing' },
  {
    name: 'Phosphogypsum',
    description: 'Byproduct for construction, requires careful handling',
  },
]

async function run() {
  try {
    if (!process.env.MONGODB_URI_DRIVER) {
      throw new Error('MONGODB_URI_DRIVER is not defined in .env')
    }

    await mongoose.connect(process.env.MONGODB_URI_DRIVER)
    await Category.insertMany(categories)
    console.log('✅ Categories inserted successfully')
  } catch (error) {
    console.error('❌ Error inserting categories:', error)
  } finally {
    await mongoose.connection.close()
  }
}

run()
