"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.addCategory = exports.getCategories = void 0;
const category_model_1 = __importDefault(require("../models/category.model"));
const getCategories = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const categories = yield category_model_1.default.find();
        if (categories.length === 0) {
            return res.status(404).json({
                statusCode: '05',
                error: 'No categories found',
            });
        }
        return res.status(200).json({
            statusCode: '00',
            data: categories.map((cat) => ({
                id: cat._id,
                name: cat.name,
                description: cat.description,
            })),
        });
    }
    catch (error) {
        return res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during category retrieval',
        });
    }
});
exports.getCategories = getCategories;
const addCategory = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { name, description } = req.body;
        const existingCategory = yield category_model_1.default.findOne({ name });
        if (existingCategory) {
            return res.status(400).json({
                statusCode: '01',
                error: 'Category already exists',
            });
        }
        const category = new category_model_1.default({ name, description });
        yield category.save();
        return res.status(201).json({
            statusCode: '00',
            message: 'Category added successfully',
            data: {
                id: category._id,
                name: category.name,
                description: category.description,
            },
        });
    }
    catch (error) {
        return res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during category addition',
        });
    }
});
exports.addCategory = addCategory;
