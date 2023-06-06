import { BadRequestException, Body, Controller, Param, Post, Put } from '@nestjs/common';
import { UsersService } from './users.service';
import { UserCreateDto } from './models/user-create.dto';
import { UserUpdateDto } from './models/user-update.dto';

@Controller('users')
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Post('register')
  async register(@Body() userCreateDto: UserCreateDto) {
    if (userCreateDto.password !== userCreateDto.confirmPassword) {
      throw new BadRequestException('Passwords do not match!');
    }
    const newUser = await this.userService.createUser(userCreateDto);
    return newUser;
  } 

  @Put(':id')
  async updateUserInfo(
    @Param('id') id: number,
    @Body() userUpdateDto: UserUpdateDto) {
      return await this.userService.updateUserInfo(id, userUpdateDto);
  }
}
