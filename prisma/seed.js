const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");

const prisma = new PrismaClient();

async function main() {
  const hashedPassword = await bcrypt.hash("admin123", 10);

  const admin = await prisma.user.upsert({
    where: { email: "luis@admin.com" },
    update: {},
    create: {
      name: "luis",
      email: "luis@admin.com",
      password: hashedPassword,
      type: "ADMINISTRADOR",
    },
  });

  console.log("Admin account created:", admin.email);
}

main()
  .catch((e) => console.error(e))
  .finally(() => prisma.$disconnect());
