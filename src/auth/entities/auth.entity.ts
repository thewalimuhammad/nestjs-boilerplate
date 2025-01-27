import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { OTP_EXPIRY } from 'src/constant/index.constant';

@Schema({ timestamps: true })
export default class Auth {
  @Prop()
  email: string;

  @Prop()
  otp: number;

  @Prop({ default: Date.now, expires: OTP_EXPIRY })
  expiresAt: Date;
}

export const AuthSchema = SchemaFactory.createForClass(Auth);
