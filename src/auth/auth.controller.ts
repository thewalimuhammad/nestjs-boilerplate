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
import { UpdateEmailDto } from './dto/update-email.dto';

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
        });
      }

      const queryUser = {
        email: body.email,
        isDeleted: false,
        isVerified: false,
      };
      const userExistNotVerified = await this.userModel.findOne(queryUser);
      await this.authService.sendSignupEmail(body);
      if (userExistNotVerified) {
        await this.userModel.updateOne({ email: body.email }, body);
        return res.status(HttpStatus.CREATED).send({
          message: 'Verify Pin sent to email please verify email',
        });
      }
      await this.userModel.create(body);
      return res.status(HttpStatus.CREATED).send({
        message: 'Verify Pin sent to email please verify email',
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
    }
  }

  @Post('/login')
  async userLogin(@Body() body: UserLoginDto, @Res() res) {
    try {
      const query = {
        email: body.email,
        isVerified: true,
        isDeleted: false,
      };
      const user = await this.userModel.findOne(query);
      if (!user) {
        return res.status(HttpStatus.NOT_FOUND).send({
          message: 'User not exits',
        });
      }
      const isPasswordMatched = await bcrypt.compare(
        body.password,
        user.password,
      );
      if (!isPasswordMatched) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'incorrect credential',
        });
      }
      const token = this.authService.signToken(user._id.toString());
      return res.status(HttpStatus.OK).send({
        message: 'Logged in successfully',
        data: { token: token },
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
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
        });
      }
      await this.authService.sendForgotEmail(body);

      return res.status(HttpStatus.OK).send({
        message: 'User Found and Pin sent to email',
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
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
        });
      }
      const authOTP = await this.authService.getOTP(body);
      if (!authOTP) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'OTP expired',
        });
      }

      if (Number(body.otp) !== authOTP) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'Invalid OTP',
        });
      }
      const token = this.authService.signToken(user._id.toString());
      await this.userModel.updateOne(
        { _id: user._id },
        { $set: { isVerified: true } },
      );
      return res.status(HttpStatus.OK).send({
        message: 'OTP verified successfully',
        data: { token: token },
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
    }
  }

  @Post('/reset-password')
  @UseGuards(JwtAuthGuard)
  async resetPassword(@Body() body: resetPasswordDto, @Req() req, @Res() res) {
    try {
      if (body.password !== body.confirmPassword) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'New Password and Confirm Password are not matched',
        });
      }
      await this.userModel.findByIdAndUpdate(req.user.id, {
        password: body.password,
      });
      return res.status(HttpStatus.OK).send({
        message: 'Password reset successfully',
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
    }
  }

  @Get('/verify-token')
  @UseGuards(JwtAuthGuard)
  async verifyToken(@Req() req, @Res() res) {
    try {
      const user = await this.userModel
        .findById(req.user.id)
        .select('-password');
      return res.status(HttpStatus.OK).send({
        message: 'Token verified',
        data: user,
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
    }
  }

  @Patch('/update-email')
  @UseGuards(JwtAuthGuard)
  async updateEmail(@Body() body: UpdateEmailDto, @Req() req, @Res() res) {
    try {
      const query = { email: body.newEmail, isDeleted: false };
      const userExist = await this.userModel.findOne(query);
      if (userExist) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'Email already registered.',
        });
      }
      const currentUser = await this.userModel.findById(req.user.id);
      const isPasswordMatched = await bcrypt.compare(
        body.password,
        currentUser.password,
      );
      if (!isPasswordMatched) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'Incorrect password',
        });
      }
      await this.authService.sendUpdateEmail({
        name: currentUser.name,
        email: currentUser.email,
        newEmail: body.newEmail,
      });
      const user = await this.userModel
        .findByIdAndUpdate(req.user.id, { email: body.newEmail }, { new: true })
        .select('-password');
      return res.status(HttpStatus.OK).send({
        message: 'Email updated successfully',
        data: { user },
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
    }
  }

  @Patch('/update-profile')
  @UseGuards(JwtAuthGuard)
  async updateProfile(@Body() body: UserSignUpDto, @Req() req, @Res() res) {
    try {
      await this.userModel.findByIdAndUpdate(req.user.id, body);
      return res.status(HttpStatus.OK).send({
        message: 'Profile updated successfully',
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
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
        });
      }
      if (body.newPassword !== body.confirmPassword) {
        return res.status(HttpStatus.BAD_REQUEST).send({
          message: 'New Password and Confirm Password are not matched',
        });
      }
      await this.authService.sendUpdatePasswordEmail({
        name: user.name,
        email: user.email,
      });
      user.password = body.newPassword;
      await user.save();
      return res.status(HttpStatus.OK).send({
        message: 'Password updated successfully',
      });
    } catch (error) {
      return res.status(500).send({
        error: error.message,
      });
    }
  }
}
