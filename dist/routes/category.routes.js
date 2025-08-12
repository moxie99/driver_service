"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const express_validator_1 = require("express-validator");
const category_controller_1 = require("../controllers/category.controller");
const auth_middleware_1 = require("../middleware/auth.middleware");
const validate_middleware_1 = require("../middleware/validate.middleware");
const router = (0, express_1.Router)();
router.get('/categories', category_controller_1.getCategories);
router.post('/categories', auth_middleware_1.authenticate, [
    (0, express_validator_1.body)('name').notEmpty().withMessage('Category name is required'),
    (0, express_validator_1.body)('description')
        .notEmpty()
        .withMessage('Category description is required'),
], validate_middleware_1.validateRequest, category_controller_1.addCategory);
exports.default = router;
