import { Module } from "@nestjs/common";
import { GoogleAuthenticationController } from "./google-auth.controller";
import { GoogleAuthenticationService } from "./google-auth.service";
import { GoogleStrategy } from "./strategy/google-strategy";
import { TypeOrmModule } from "@nestjs/typeorm";
import { SocialLoginInfo } from "./entities/social-auth.entity";
import { TypeOrmExModule } from "src/common/repository-module/typeorm-ex.decorator";
import { SocialLoginInfoRepository } from "./repositories/socialLogin-info.repository";
import { GoogleAuthGuard } from "./guard/google-guard";
import { SessionSerializer } from "./serializer/serializer";
import { User } from "src/users/entities/users.entity";
import { UsersRepository } from "src/users/repositories/users.repository";
import { UsersService } from "src/users/users.service";

@Module({
  imports: [
    TypeOrmModule.forFeature([SocialLoginInfo, User]),
    TypeOrmExModule.forCustomRepository([SocialLoginInfoRepository, UsersRepository]),
  ],
  controllers: [GoogleAuthenticationController],
  providers: [UsersService, GoogleAuthenticationService, SessionSerializer, GoogleStrategy, GoogleAuthGuard]
})
export class GoogleAuthenticationModule {}