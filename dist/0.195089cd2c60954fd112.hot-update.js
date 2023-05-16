"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 147:
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
exports.JwtTwoFactorStrategy = void 0;
const common_1 = __webpack_require__(6);
const passport_1 = __webpack_require__(27);
const passport_jwt_1 = __webpack_require__(31);
const users_service_1 = __webpack_require__(9);
let JwtTwoFactorStrategy = class JwtTwoFactorStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy, 'jwt-two-factor') {
    constructor(userService) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromExtractors([(req) => {
                    var _a;
                    return (_a = req === null || req === void 0 ? void 0 : req.cookies) === null || _a === void 0 ? void 0 : _a.access_token;
                }]),
            secretOrKey: process.env.JWT_ACCESS_SECRET
        });
        this.userService = userService;
    }
    async validate(payload) {
        const user = await this.userService.findUserById(payload.id);
        if (!user.isTwoFactorAuthenticationEnabled) {
            return user;
        }
        if (payload.isSecondFactorAuthenticated !== true) {
            return false;
        }
        console.log(user.isTwoFactorAuthenticationEnabled);
        console.log(payload.isSecondFactorAuthenticated);
        return user;
    }
};
JwtTwoFactorStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object])
], JwtTwoFactorStrategy);
exports.JwtTwoFactorStrategy = JwtTwoFactorStrategy;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("3ed6e659dea078619a39")
/******/ })();
/******/ 
/******/ }
;