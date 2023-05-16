import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { UsersService } from "src/users/users.service";
import { Payload } from "../payload/payload.interface";
import { Request } from "express";
import { User } from "src/users/entities/users.entity";
import { JwtService } from "@nestjs/jwt";

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh-token') {
  constructor(
    private readonly userService: UsersService,
    private readonly jwtService: JwtService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request) => {
          return request?.cookies?.refresh_token;
        },
      ]),
      secretOrKey: process.env.JWT_REFRESH_SECRET,
      passReqToCallback: true,
    })
  }

  async validate(req: Request, payload: Payload) {
    const refreshToken = req.cookies['refresh_token'];
    await this.jwtService.verify(refreshToken, { secret: process.env.JWT_REFRESH_SECRET }) as Payload;
    const user: User = await this.userService.getUserIfRefreshTokenMatches(
      refreshToken,
      payload.id
    );
    return user;
  }
}