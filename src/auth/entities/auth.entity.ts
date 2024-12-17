import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

@Schema({ timestamps: true })
export default class Auth {
  @Prop()
  email: string;

  @Prop()
  otp: number;

  @Prop({ default: Date.now, expires: '60s' })
  expiresAt: Date;
}

export const AuthSchema = SchemaFactory.createForClass(Auth);
