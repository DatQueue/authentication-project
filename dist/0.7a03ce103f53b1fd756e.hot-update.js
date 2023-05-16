"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 49:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TestController = void 0;
const common_1 = __webpack_require__(6);
const test_service_1 = __webpack_require__(50);
const throttler_1 = __webpack_require__(35);
let TestController = class TestController {
    constructor(testService) {
        this.testService = testService;
    }
    async getHello() {
        return await this.testService.sayHello();
    }
    async getUsers() {
        return [];
    }
    async getUsersPosts() {
        return {};
    }
};
__decorate([
    (0, throttler_1.SkipThrottle)(),
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", typeof (_b = typeof Promise !== "undefined" && Promise) === "function" ? _b : Object)
], TestController.prototype, "getHello", null);
__decorate([
    (0, common_1.Get)('/users'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], TestController.prototype, "getUsers", null);
__decorate([
    (0, throttler_1.Throttle)(5, 15),
    (0, common_1.Get)('/users/posts'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], TestController.prototype, "getUsersPosts", null);
TestController = __decorate([
    (0, common_1.Controller)('test'),
    __metadata("design:paramtypes", [typeof (_a = typeof test_service_1.TestService !== "undefined" && test_service_1.TestService) === "function" ? _a : Object])
], TestController);
exports.TestController = TestController;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("61c2d7f8b402d6fb1109")
/******/ })();
/******/ 
/******/ }
;