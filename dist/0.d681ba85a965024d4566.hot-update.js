"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 150:
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
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TwoFATestController = void 0;
const common_1 = __webpack_require__(6);
const jwt_twoFactor_guard_1 = __webpack_require__(148);
let TwoFATestController = class TwoFATestController {
    async accessWithTwoFA() {
        return {
            msg: "Succeed!",
        };
    }
};
__decorate([
    (0, common_1.UseGuards)(jwt_twoFactor_guard_1.default),
    (0, common_1.Get)('access-2fa'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], TwoFATestController.prototype, "accessWithTwoFA", null);
TwoFATestController = __decorate([
    (0, common_1.Controller)('test')
], TwoFATestController);
exports.TwoFATestController = TwoFATestController;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("7d12a31916ca1d9b6009")
/******/ })();
/******/ 
/******/ }
;