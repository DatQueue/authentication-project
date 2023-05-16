import { ConfigService } from "@nestjs/config";
import { User } from "../../users/entities/users.entity";
import { UsersService } from "../../users/users.service";
import { authenticator } from "otplib";
import { Response } from "express";
import { toFileStream } from "qrcode";
import { Injectable } from "@nestjs/common";

@Injectable()
export class TwoFactorAuthenticationService {
  constructor (
    private readonly userService: UsersService,
    private readonly configService: ConfigService
  ) {}

  public async generateTwoFactorAuthenticationSecret(user: User): Promise<any> {
    const secret = authenticator.generateSecret();

    const otpAuthUrl = authenticator.keyuri(user.email, this.configService.get('TWO_FACTOR_AUTHENTICATION_APP_NAME'), secret);

    await this.userService.setTwoFactorAuthenticationSecret(secret, user.id);

    return {
      secret,
      otpAuthUrl
    }
  }

  public async pipeQrCodeStream(stream: Response, otpAuthUrl: string): Promise<void> {
    return toFileStream(stream, otpAuthUrl);
  }

  public async isTwoFactorAuthenticationCodeValid(twoFactorAuthenticationCode: string, user: User) {
    if (!user.twoFactorAuthenticationSecret) {
      return false; // 혹은 다른 처리 방식을 선택할 수 있습니다.
    }
    
    return authenticator.verify({
      token: twoFactorAuthenticationCode,
      secret: user.twoFactorAuthenticationSecret,
    })
  }
}