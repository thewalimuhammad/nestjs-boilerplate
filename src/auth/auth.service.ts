import { Injectable } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import Auth from './entities/auth.entity';
import { verifyOTPDto } from './dto/verify-otp.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('Auth') private readonly authModel: Model<Auth>,
    private jwtService: JwtService,
  ) {}

  signToken(id) {
    return this.jwtService.sign(
      { id },
      {
        secret: process.env.JWT_SECRET_KEY,
        expiresIn: process.env.JWT_EXPIRATION,
      },
    );
  }

  async sendMail(body: CreateAuthDto) {
    try {
      const otp = this.generateOTP();
      await this.authModel.findOneAndDelete({ email: body.email });
      const userOTP = await this.authModel.create({ email: body.email, otp });
      return userOTP;
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
