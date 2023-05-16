"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 26:
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
exports.JwtAccessAuthGuard = void 0;
const common_1 = __webpack_require__(6);
const jwt_1 = __webpack_require__(23);
const users_service_1 = __webpack_require__(9);
let JwtAccessAuthGuard = class JwtAccessAuthGuard {
    constructor(jwtService, userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }
    async canActivate(context) {
        try {
            const request = context.switchToHttp().getRequest();
            const access_token = request.cookies['access_token'];
            const decodedToken = await this.jwtService.verifyAsync(access_token);
            if (!decodedToken) {
                return false;
            }
            const userId = decodedToken.id;
            const user = await this.userService.findUserById(userId);
            if (!user) {
                return false;
            }
            request.user = this.mapPayloadToUser(decodedToken, user);
            return true;
        }
        catch (err) {
            return false;
        }
    }
    mapPayloadToUser(payload, user) {
        return Object.assign(Object.assign({}, user), payload);
    }
};
JwtAccessAuthGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _a : Object, typeof (_b = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _b : Object])
], JwtAccessAuthGuard);
exports.JwtAccessAuthGuard = JwtAccessAuthGuard;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("b6c878c645ef70896e58")
/******/ })();
/******/ 
/******/ }
;