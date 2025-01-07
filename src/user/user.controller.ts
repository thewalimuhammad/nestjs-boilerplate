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
import { Role } from 'src/constant/index.constant';

@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService,
    @InjectModel('User') private readonly userModel: Model<User>,
  ) {}

  @Get('')
  @UseGuards(JwtAuthGuard)
  async findAllUser(@Req() req, @Res() res) {
    try {
      const userExists = await this.userModel.findById(req.user.id);
      if (userExists.role !== Role.SUPER_ADMIN) {
        return res.status(HttpStatus.UNAUTHORIZED).send({
          message: 'Unauthorized',
          data: {},
        });
      }
      const users = await this.userModel.find();
      return res.status(HttpStatus.OK).send({
        message: 'All users',
        data: users,
      });
    } catch (error) {
      throw error;
    }
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  async findOneUser(@Req() req, @Param('id') id: string, @Res() res) {
    try {
      const user = await this.userModel.findById(req.user.id);
      if (user.role !== Role.SUPER_ADMIN) {
        return res.status(HttpStatus.UNAUTHORIZED).send({
          message: 'Unauthorized',
          data: {},
        });
      }
      const userExists = await this.userModel.findById(id);
      return res.status(HttpStatus.OK).send({
        message: 'User',
        data: userExists,
      });
    } catch (error) {
      throw error;
    }
  }

  @Patch(':id')
  @UseGuards(JwtAuthGuard)
  async updateOneUser(
    @Param('id') id: string,
    @Body() body: UpdateUserDto,
    @Req() req,
    @Res() res,
  ) {
    try {
      const user = await this.userModel.findById(req.user.id);
      if (user.role !== Role.SUPER_ADMIN) {
        return res.status(HttpStatus.UNAUTHORIZED).send({
          message: 'Unauthorized',
          data: {},
        });
      }
      const updatedUser = await this.userModel.findByIdAndUpdate(id, body, {
        new: true,
      });
      return res.status(HttpStatus.OK).send({
        message: 'User updated successfully',
        data: updatedUser,
      });
    } catch (error) {
      throw error;
    }
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard)
  async deleteOneUser(@Param('id') id: string, @Req() req, @Res() res) {
    try {
      const user = await this.userModel.findById(req.user.id);
      if (user.role !== Role.SUPER_ADMIN) {
        return res.status(HttpStatus.UNAUTHORIZED).send({
          message: 'Unauthorized',
          data: {},
        });
      }
      await this.userModel.findByIdAndUpdate(id, { isDeleted: true });
      return res.status(HttpStatus.OK).send({
        message: 'User deleted successfully',
        data: {},
      });
    } catch (error) {
      throw error;
    }
  }
}
