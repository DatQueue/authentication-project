import { Module, forwardRef } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from 'src/users/users.module';
import { UsersService } from 'src/users/users.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/users.entity';
import { TypeOrmExModule } from 'src/common/repository-module/typeorm-ex.decorator';
import { UsersRepository } from 'src/users/repositories/users.repository';
import { JwtAccessAuthGuard } from './guard/jwt-access.guard';
import { JwtRefreshStrategy } from './strategy/jwt-refresh.strategy';
import { JwtRefreshGuard } from './guard/jwt-refresh.guard';
import { APIRateLimitModule } from '../common/modules/rate-limit.module';
import { TwoFactorAuthenticationController } from './2fa/twoFactorAuthentication.controller';
import { TwoFactorAuthenticationService } from './2fa/twoFactorAuthentication.service';
import { JwtTwoFactorStrategy } from './2fa/strategy/jwt-twoFactor.strategy';
import JwtTwoFactorGuard from './2fa/guard/jwt-twoFactor.guard';
import { GoogleAuthenticationModule } from './google-oauth2/google-auth.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    TypeOrmExModule.forCustomRepository([UsersRepository]),
    PassportModule.register({
      session: true,
    }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_ACCESS_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_ACCESS_EXPIRATION_TIME'),
        } 
      }),
      inject: [ConfigService],
    }),
    forwardRef(() => UsersModule),
    APIRateLimitModule,
    GoogleAuthenticationModule,
  ],
  controllers: [AuthController, TwoFactorAuthenticationController],
  providers: [AuthService, UsersService, TwoFactorAuthenticationService, JwtRefreshStrategy,JwtTwoFactorStrategy, JwtAccessAuthGuard, JwtRefreshGuard, JwtTwoFactorGuard],
})
export class AuthModule {}
