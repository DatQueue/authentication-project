"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 22:
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
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const common_1 = __webpack_require__(6);
const jwt_1 = __webpack_require__(23);
const bcrypt = __webpack_require__(10);
const users_service_1 = __webpack_require__(9);
const config_1 = __webpack_require__(15);
let AuthService = class AuthService {
    constructor(userService, jwtService, configService) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.configService = configService;
    }
    async validateUser(loginDto) {
        const user = await this.userService.findUserByEmail(loginDto.email);
        if (!user) {
            throw new common_1.NotFoundException('User not found!');
        }
        if (!await bcrypt.compare(loginDto.password, user.password)) {
            throw new common_1.BadRequestException('Invalid credentials!');
        }
        return user;
    }
    async getDecodedRefreshToken(refreshTokenDto) {
        const { refresh_token } = refreshTokenDto;
        const decodedRefreshToken = await this.jwtService.verify(refresh_token, { secret: process.env.JWT_REFRESH_SECRET });
        return decodedRefreshToken;
    }
    async refresh(refreshTokenDto) {
        const decodedRefreshToken = await this.getDecodedRefreshToken(refreshTokenDto);
        const userId = decodedRefreshToken.id;
        const refreshTokenExpTime = parseInt(decodedRefreshToken.exp, 10) * 1000;
        const currentTime = Date.now();
        console.log(refreshTokenExpTime, currentTime);
        if (refreshTokenExpTime < currentTime) {
            await this.userService.removeRefreshToken(userId);
        }
        const user = await this.userService.getUserIfRefreshTokenMatches(refreshTokenDto.refresh_token, userId);
        if (!user) {
            throw new common_1.UnauthorizedException('Invalid user!');
        }
        const accessToken = await this.generateAccessToken(user);
        return { accessToken };
    }
    async removeRFTDataIfTokenExpired(userId) {
        const currentTime = Date.now();
        const refreshTokenExpTime = (await this.userService.getCurrentRefreshTokenExp()).getTime();
        const usersWithExpiredRefreshTokens = await this.userService.findUsersWithExpiredTokens(currentTime);
        setTimeout(async () => {
            await this.userService.removeRefreshToken(userId);
        }, refreshTokenExpTime - currentTime);
    }
    async generateAccessToken(user) {
        const payload = {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
        };
        return this.jwtService.signAsync(payload);
    }
    async generateRefreshToken(user) {
        const payload = {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
        };
        return this.jwtService.signAsync({ id: payload.id }, {
            secret: this.configService.get('JWT_REFRESH_SECRET'),
            expiresIn: this.configService.get('JWT_REFRESH_EXPIRATION_TIME'),
        });
    }
};
AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object, typeof (_c = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _c : Object])
], AuthService);
exports.AuthService = AuthService;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("b4ed938050c293633e60")
/******/ })();
/******/ 
/******/ }
;