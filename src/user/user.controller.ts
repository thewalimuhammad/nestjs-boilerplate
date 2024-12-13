import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Req,
  Res,
  HttpStatus,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import User from './entities/user.entity';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { JwtAuthGuard } from 'src/auth/guards/jwt.guard';

@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService,
    @InjectModel('User') private readonly userModel: Model<User>,
  ) {}

  @Get('/profile')
  @UseGuards(JwtAuthGuard)
  async userProfile(@Req() req, @Res() res) {
    try {
      const userExists = await this.userModel
        .findById(req.user.id)
        .select('name email role isVerified');
      return res.status(HttpStatus.OK).send({
        message: 'User profile',
        data: userExists,
      });
    } catch (error) {
      throw error;
    }
  }
}
