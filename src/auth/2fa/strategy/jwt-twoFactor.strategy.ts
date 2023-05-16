import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";
import { Payload } from "src/auth/payload/payload.interface";
import { UsersService } from "src/users/users.service";

@Injectable()
export class JwtTwoFactorStrategy extends PassportStrategy(
  Strategy,
  'jwt-two-factor'
) {
  constructor(
    private readonly userService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([(req: Request) => {
        return req?.cookies?.access_token;
      } ]),
      secretOrKey: process.env.JWT_ACCESS_SECRET
    });
  }

  async validate(payload: Payload) {
    const user = await this.userService.findUserById(payload.id);
    console.log(payload);
    console.log(user.isTwoFactorAuthenticationEnabled);
    console.log(payload.isSecondFactorAuthenticated);
    if (!user.isTwoFactorAuthenticationEnabled) {
      return user;
    }
    if (payload.isSecondFactorAuthenticated) {
      return user; 
    }
    return null;
  }
}