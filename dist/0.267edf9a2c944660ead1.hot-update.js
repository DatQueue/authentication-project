"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 72:
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
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.clearJwtCookieInterceptor = void 0;
const common_1 = __webpack_require__(6);
const rxjs_1 = __webpack_require__(73);
const auth_service_1 = __webpack_require__(22);
let clearJwtCookieInterceptor = class clearJwtCookieInterceptor {
    constructor(authService) {
        this.authService = authService;
    }
    async intercept(context, next) {
        const req = context.switchToHttp().getRequest();
        const res = context.switchToHttp().getResponse();
        const user = req.user;
        const refreshTokenValidityPeriod = await this.authService.removeRFTDataIfTokenExpired(user.id);
        return next.handle().pipe((0, rxjs_1.tap)(() => {
            return new Promise((resolve, reject) => {
                setTimeout(() => {
                    res.clearCookie('access_token');
                    res.clearCookie('refresh_token');
                    resolve(null);
                }, refreshTokenValidityPeriod);
            });
        }));
    }
};
clearJwtCookieInterceptor = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object])
], clearJwtCookieInterceptor);
exports.clearJwtCookieInterceptor = clearJwtCookieInterceptor;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("42d439ccb37d164f7981")
/******/ })();
/******/ 
/******/ }
;