import { ForbiddenException, HttpCode, Injectable } from "@nestjs/common";
import { User, Bookmark, Prisma } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from "argon2";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) {}
    async signup(dto: AuthDto) {
        // Hash the password
        const hash = await argon.hash(dto.password);

        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash: hash
                }
            });
            return user;
        } catch (e) {
            if (e instanceof Prisma.PrismaClientKnownRequestError) {
                if (e.code === "P2002") {
                    // means email already exists
                    throw new ForbiddenException("Credentials taken");
                }
            }

            throw e;
        }
    }

    async login(dto: AuthDto) {
        // find user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        });

        // if user doesn't exist throw exception
        if (!user) throw new ForbiddenException("Credentials incorrect");

        // compare password
        const pwMatches = await argon.verify(user.hash, dto.password);
        if (!pwMatches) throw new ForbiddenException("Credentials incorrect");

        // return the user
        return user;
    }
}
