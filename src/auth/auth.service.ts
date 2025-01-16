import { Injectable } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import Auth from './entities/auth.entity';
import { verifyOTPDto } from './dto/verify-otp.dto';
import { EmailsService } from 'src/common/emails/emails.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('Auth') private readonly authModel: Model<Auth>,
    private jwtService: JwtService,
    private emailsService: EmailsService,
  ) {}

  signToken(id: string) {
    return this.jwtService.sign(
      { id },
      {
        secret: process.env.JWT_SECRET_KEY,
        expiresIn: process.env.JWT_EXPIRATION,
      },
    );
  }

  async sendSignupEmail(body: CreateAuthDto) {
    try {
      const otp = this.generateOTP();
      await this.authModel.findOneAndDelete({ email: body.email });
      await this.authModel.create({ email: body.email, otp });
      const emailSent = await this.emailsService.SignupEmail({
        name: body.name,
        email: body.email,
        otp: otp,
      });
      return emailSent;
    } catch (error) {
      throw error;
    }
  }

  async sendForgotEmail(body: CreateAuthDto) {
    try {
      const otp = this.generateOTP();
      await this.authModel.findOneAndDelete({ email: body.email });
      await this.authModel.create({ email: body.email, otp });
      const emailSent = await this.emailsService.forgetPasswordEmail({
        name: body.name,
        email: body.email,
        otp: otp,
      });
      return emailSent;
    } catch (error) {
      throw error;
    }
  }

  async sendUpdateEmail(body: any) {
    try {
      const emailSent = await this.emailsService.updateEmail({
        name: body.name,
        email: body.email,
        newEmail: body.newEmail,
      });
      return emailSent;
    } catch (error) {
      throw error;
    }
  }

  async sendUpdatePasswordEmail(body: any) {
    try {
      const emailSent = await this.emailsService.updatePasswordEmail({
        name: body.name,
        email: body.email,
      });
      return emailSent;
    } catch (error) {
      throw error;
    }
  }

  async getOTP(body: verifyOTPDto) {
    try {
      const user = await this.authModel.findOne({ email: body.email });
      if (!user) {
        return null;
      }
      return user.otp;
    } catch (error) {
      throw error;
    }
  }

  generateOTP() {
    return crypto.randomInt(1000, 9999);
  }
}
