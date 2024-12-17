import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Req,
  UseGuards,
  Res,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt.guard';
import User from 'src/user/entities/user.entity';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { UserLoginDto } from './dto/login-user.dto';
import { UserSignUpDto } from './dto/signup-user.dto';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { verifyOTPDto } from './dto/verify-otp.dto';
import { resetPasswordDto } from './dto/reset-password.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';

@Controller('auth')
export class AuthController {
  constructor(
    @InjectModel('User') private readonly userModel: Model<User>,
    private readonly authService: AuthService,
  ) {}

  @Post('/signup')
  async userSignUp(@Body() body: UserSignUpDto, @Res() res) {
    try {
      const query = {
        email: body.email,
        isDeleted: false,
        isVerified: true,
      };
      const userExist = await this.userModel.findOne(query);
      if (userExist) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'Email already registered.',
          data: {},
        });
      }

      const queryUser = {
        email: body.email,
        isDeleted: false,
        isVerified: false,
      };
      const userExistNotVerified = await this.userModel.findOne(queryUser);
      const setOTP = await this.authService.sendMail(body);
      console.log(setOTP.otp);
      if (userExistNotVerified) {
        await this.userModel.updateOne({ email: body.email }, body);
        return res.status(HttpStatus.CREATED).send({
          message:
            'User registered successfully please verify OTP sent to email',
          data: {},
        });
      }
      await this.userModel.create(body);
      return res.status(HttpStatus.CREATED).send({
        message: 'User registered successfully please verify OTP sent to email',
        data: {},
      });
    } catch (error) {
      throw error;
    }
  }

  @Post('/login')
  async userLogin(@Body() body: UserLoginDto, @Res() res) {
    try {
      const query = {
        email: body.email,
        isDeleted: false,
      };
      const user = await this.userModel.findOne(query);
      if (!user) {
        return res.status(HttpStatus.NOT_FOUND).send({
          message: 'incorrect credential.',
          data: {},
        });
      }
      const isPasswordMatched = await bcrypt.compare(
        body.password,
        user.password,
      );
      if (!isPasswordMatched) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'incorrect credential',
          data: {},
        });
      }
      const token = this.authService.signToken(user._id);
      return res.status(HttpStatus.OK).send({
        message: 'Logged in successfully',
        data: { token: token },
      });
    } catch (error) {
      throw error;
    }
  }

  @Post('/forgot-password')
  async forgotPassword(@Body() body: ForgetPasswordDto, @Res() res) {
    try {
      const query = { email: body.email, isDeleted: false };
      const user = await this.userModel.findOne(query);
      if (!user) {
        return res.status(HttpStatus.NOT_FOUND).send({
          message: 'User Not found',
          data: {},
        });
      }
      const setOTP = await this.authService.sendMail(body);
      console.log(setOTP.otp);
      return res.status(HttpStatus.OK).send({
        message: 'User Found and OTP sent to email',
        data: {},
      });
    } catch (error) {
      throw error;
    }
  }

  @Post('/verify-otp')
  async verifyOTP(@Body() body: verifyOTPDto, @Res() res) {
    try {
      const query = { email: body.email, isDeleted: false };
      const user = await this.userModel.findOne(query);
      if (!user) {
        return res.status(HttpStatus.NOT_FOUND).send({
          message: 'User not found',
          data: {},
        });
      }
      const authOTP = await this.authService.getOTP(body);
      if (!authOTP) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'OTP expired',
          data: {},
        });
      }

      if (Number(body.otp) !== authOTP) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'Invalid OTP',
          data: {},
        });
      }
      const token = this.authService.signToken(user._id);
      await this.userModel.updateOne(
        { _id: user._id },
        { $set: { isVerified: true } },
      );
      return res.status(HttpStatus.OK).send({
        message: 'OTP verified successfully',
        data: { token: token },
      });
    } catch (error) {
      console.log('error', error);
      throw error;
    }
  }

  @Post('/reset-password')
  @UseGuards(JwtAuthGuard)
  async resetPassword(@Body() body: resetPasswordDto, @Req() req, @Res() res) {
    try {
      if (body.password !== body.confirmPassword) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'New Password and Confirm Password are not matched',
          data: {},
        });
      }
      await this.userModel.findByIdAndUpdate(req.user.id, {
        password: body.password,
      });
      return res.status(HttpStatus.OK).send({
        message: 'Password reset successfully',
        data: {},
      });
    } catch (error) {
      throw error;
    }
  }

  @Patch('/update-password')
  @UseGuards(JwtAuthGuard)
  async updatePassword(
    @Body() body: UpdatePasswordDto,
    @Req() req,
    @Res() res,
  ) {
    try {
      const user = await this.userModel.findById(req.user.id);
      const matched = await bcrypt.compare(body.currentPassword, user.password);
      if (!matched) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'Password not matched',
          data: {},
        });
      }
      if (body.newPassword !== body.confirmPassword) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'New Password and Confirm Password are not matched',
          data: {},
        });
      }
      user.password = body.newPassword;
      await user.save();
      return res.status(HttpStatus.OK).send({
        message: 'Password updated successfully',
        data: {},
      });
    } catch (error) {
      console.log('error', error);
      throw error;
    }
  }

  @Get('/verify-token')
  @UseGuards(JwtAuthGuard)
  async verifyToken(@Req() req, @Res() res) {
    return res.status(HttpStatus.OK).send({
      message: 'Token verified',
      data: req.user,
    });
  }
}
