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
  Query,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import User from './entities/user.entity';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { JwtAuthGuard } from 'src/auth/guards/jwt.guard';
import { Role } from 'src/constant/index.constant';
import { PaginationDto } from 'src/common/dtos/pagination.dto';

@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService,
    @InjectModel('User') private readonly userModel: Model<User>,
  ) {}

  @Get('')
  @UseGuards(JwtAuthGuard)
  async findAllUser(
    @Req() req,
    @Res() res,
    @Query() queryParam: PaginationDto,
  ) {
    try {
      let { page, limit, search, role } = queryParam;
      page = Number(page) || 1;
      limit = Number(limit) || 10;
      search = search || '';
      const skip = (page - 1) * limit;

      const userExists = await this.userModel.findById(req.user.id);
      if (userExists.role !== Role.SUPER_ADMIN) {
        return res.status(HttpStatus.UNAUTHORIZED).send({
          message: 'Unauthorized',
        });
      }

      const query = {
        name: { $regex: search, $options: 'i' },
        role: role
          ? { $in: role.split(',') }
          : { $in: [Role.USER, Role.ADMIN, Role.SUPER_ADMIN] },
      };

      const users = await this.userModel
        .find(query)
        .sort({ createdAt: -1 })
        .select('-password')
        .skip(skip)
        .limit(limit);

      const totalUsers = await this.userModel.countDocuments(query);

      return res.status(HttpStatus.OK).send({
        message: 'All users',
        data: {
          total: totalUsers,
          page: page,
          limit: limit,
          totalPages: Math.ceil(totalUsers / limit),
          users: users,
        },
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
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
        });
      }
      const userExists = await this.userModel.findById(id);
      return res.status(HttpStatus.OK).send({
        message: 'User',
        data: userExists,
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
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
      return res.status(500).send({
        error: error.message,
      });
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
        });
      }
      await this.userModel.findByIdAndUpdate(id, { isDeleted: true });
      return res.status(HttpStatus.OK).send({
        message: 'User deleted successfully',
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
    }
  }
}
