"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 77:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IpAuthUserRepository = void 0;
const typeorm_1 = __webpack_require__(13);
const ip_auth_user_entity_1 = __webpack_require__(72);
const typeorm_ex_module_1 = __webpack_require__(12);
let IpAuthUserRepository = class IpAuthUserRepository extends typeorm_1.Repository {
};
IpAuthUserRepository = __decorate([
    (0, typeorm_ex_module_1.CustomRepository)(ip_auth_user_entity_1.IPAuthUser)
], IpAuthUserRepository);
exports.IpAuthUserRepository = IpAuthUserRepository;


/***/ }),

/***/ 8:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersModule = void 0;
const common_1 = __webpack_require__(6);
const users_service_1 = __webpack_require__(9);
const users_controller_1 = __webpack_require__(16);
const typeorm_1 = __webpack_require__(7);
const users_entity_1 = __webpack_require__(14);
const typeorm_ex_decorator_1 = __webpack_require__(19);
const users_repository_1 = __webpack_require__(11);
const ip_auth_user_entity_1 = __webpack_require__(72);
const ip_auth_entity_1 = __webpack_require__(73);
const ip_auth_repository_1 = __webpack_require__(76);
const ip_auth_user_repository_1 = __webpack_require__(77);
let UsersModule = class UsersModule {
};
UsersModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([users_entity_1.User, ip_auth_entity_1.IPAuthentication, ip_auth_user_entity_1.IPAuthUser]),
            typeorm_ex_decorator_1.TypeOrmExModule.forCustomRepository([users_repository_1.UsersRepository, ip_auth_repository_1.IpAuthRepository, ip_auth_user_repository_1.IpAuthUserRepository]),
        ],
        providers: [users_service_1.UsersService],
        controllers: [users_controller_1.UsersController]
    })
], UsersModule);
exports.UsersModule = UsersModule;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("6bb09773657f3e7ed0d9")
/******/ })();
/******/ 
/******/ }
;