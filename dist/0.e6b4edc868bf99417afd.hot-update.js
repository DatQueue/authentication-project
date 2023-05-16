"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 30:
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
exports.JwtAccessStrategy = void 0;
const passport_1 = __webpack_require__(27);
const passport_jwt_1 = __webpack_require__(31);
const users_service_1 = __webpack_require__(9);
const common_1 = __webpack_require__(6);
const jwt_1 = __webpack_require__(23);
const cookieExtractor = (req) => {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['access_token'];
    }
    return token;
};
let JwtAccessStrategy = class JwtAccessStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy, 'jwt-access-token') {
    constructor(userService, jwtService) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromExtractors([
                passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
                cookieExtractor,
            ]),
            secretOrKey: process.env.JWT_ACCESS_SECRET,
            passReqToCallback: true,
        });
        this.userService = userService;
        this.jwtService = jwtService;
    }
    async validate(req, payload) {
        const access_token = req.cookies['access_token'];
        const { id } = payload;
        const user = await this.userService.findUserById(id);
        if (!user) {
            throw new Error();
        }
        const verifiedUser = await this.jwtService.verify(access_token);
        return verifiedUser;
    }
};
JwtAccessStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object])
], JwtAccessStrategy);
exports.JwtAccessStrategy = JwtAccessStrategy;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("9eb7597e2c34e0ce8e03")
/******/ })();
/******/ 
/******/ }
;