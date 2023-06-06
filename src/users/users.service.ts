import { HttpException, HttpStatus, Injectable, NotFoundException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UsersRepository } from './repositories/users.repository';
import { UserCreateDto } from 'src/users/models/user-create.dto';
import { User } from './entities/users.entity';
import { UserUpdateDto } from './models/user-update.dto';
import { ConfigService } from '@nestjs/config';
import { UpdateResult } from 'typeorm';
import { SocialLoginInfoDto } from 'src/auth/google-oauth2/utils/socialLogin-info.dto';

@Injectable()
export class UsersService {
  constructor(
    private readonly userRepository: UsersRepository,
    private readonly configService: ConfigService,
  ) {}

  async createUser(newUser: UserCreateDto): Promise<User> {
    const userFind: User = await this.userRepository.findOne({
      where: {
        email: newUser.email,
      }
    });
    if (userFind) {
      throw new HttpException('UserEmail already used!', HttpStatus.BAD_REQUEST);
    }

    const saltOrRounds = 12;
    const hashedPassword = await this.hashPassword(newUser.password, saltOrRounds);
    return this.userRepository.save({
      ...newUser,
      password: hashedPassword,
      confirmPassword: hashedPassword
    });
  }

  async createSocialUser(socialLoginInfoDto: SocialLoginInfoDto): Promise<User> {
    const { email, firstName, lastName, socialProvider, externalId, refreshToken } = socialLoginInfoDto;

    const newUser: User = await this.userRepository.save({
      email: email,
      firstName: firstName,
      lastName: lastName,
      socialProvider: socialProvider,
      externalId: externalId,
      socialProvidedRefreshToken: refreshToken,
    });
    return await this.userRepository.save(newUser);
  }

  private async hashPassword(password: string, saltOrRounds: number): Promise<string> {
    return bcrypt.hash(password, saltOrRounds);
  }

  async findUserByEmail(email: string): Promise<User> {
    return await this.userRepository.findOne({
      where: {
        email: email,
      }
    })
  }

  async findUserById(id: number): Promise<User> {
    return await this.userRepository.findOne({
      where: {
        id: id
      },
    })
  }

  async updateUserInfo(id: number, data: UserUpdateDto): Promise<User> {
    const user = await this.findUserById(id);

    if (!user) {
      throw new NotFoundException('해당 id의 유저 정보는 존재하지 않습니다.');
    }

    const findEmail = await this.findUserByEmail(data.email);

    if (findEmail && findEmail.id !== user.id) {
      throw new HttpException('Username already used!', HttpStatus.BAD_GATEWAY);
    }

    await this.userRepository.update(id, data);

    const updatedUser = await this.userRepository.findOne({
      where: {
        id,
      }
    });
    return updatedUser;
  }

  async updateSocialUserInfo(id: number) {
    await this.userRepository.update(id, {
      isSocialAccountRegistered: true,
    })
    const updateUser = await this.userRepository.findOne({
      where: {
        id: id,
      },
    });
    return updateUser;
  }

  async updateSocialUserRefToken(id: number, refreshToken: string) {
    await this.userRepository.update(id, {
      socialProvidedRefreshToken: refreshToken,
    })
    const updateUser = await this.userRepository.findOne({
      where: {
        id: id,
      }
    });
    return updateUser;
  }

  async deleteUser(id: number): Promise<any> {
    return this.userRepository.delete(id);
  }

  async getCurrentHashedRefreshToken(refreshToken: string) {
    const saltOrRounds = 10;
    const currentRefreshToken = await bcrypt.hash(refreshToken, saltOrRounds);
    return currentRefreshToken;
  }

  async getCurrentRefreshTokenExp(): Promise<Date> {
    const currentDate = new Date();
    const currentRefreshTokenExp = new Date(currentDate.getTime() + parseInt(this.configService.get<string>('JWT_REFRESH_EXPIRATION_TIME')));
    return currentRefreshTokenExp;
  }

  async setCurrentRefreshToken(refreshToken: string, userId: number) {
    const currentRefreshToken = await this.getCurrentHashedRefreshToken(refreshToken);
    const currentRefreshTokenExp = await this.getCurrentRefreshTokenExp();
    await this.userRepository.update(userId, {
      currentRefreshToken: currentRefreshToken,
      currentRefreshTokenExp: currentRefreshTokenExp,
    });
  }

  async getUserIfRefreshTokenMatches(refreshToken: string, userId: number): Promise<User> {
    const user: User = await this.findUserById(userId);

    if (!user.currentRefreshToken) {
      return null;
    }

    const isRefreshTokenMatching = await bcrypt.compare(
      refreshToken,
      user.currentRefreshToken
    );

    if (isRefreshTokenMatching) {
      return user;
    } 
  }

  async findUsersWithExpiredTokens(currentTime: number): Promise<User[]> {
    const queryBuilder = this.userRepository.createQueryBuilder('user');
    const usersWithExpiredTokens = await queryBuilder
      .where('user.currentRefreshTokenExp <= :currentTime', { currentTime: new Date(currentTime) })
      .getMany();
    return usersWithExpiredTokens;
  }

  async removeRefreshToken(userId: number): Promise<UpdateResult> {
    return await this.userRepository.update(userId, {
      currentRefreshToken: null,
      currentRefreshTokenExp: null,
    });
  }

  async setTwoFactorAuthenticationSecret(secret: string, userId: number): Promise<UpdateResult> {
    return this.userRepository.update(userId, {
      twoFactorAuthenticationSecret: secret,
    });
  }

  async turnOnTwoFactorAuthentication(userId: number): Promise<UpdateResult> {
    return await this.userRepository.update(userId, {
      isTwoFactorAuthenticationEnabled: true,
    });
  }

  async turnOffTwoFactorAuthentication(userId: number): Promise<UpdateResult> {
    return await this.userRepository.update(userId, {
      twoFactorAuthenticationSecret: null,
      isTwoFactorAuthenticationEnabled: false,
    })
  }
}
