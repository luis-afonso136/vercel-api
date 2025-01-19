require("dotenv").config();
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const prisma = new PrismaClient();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

app.use(express.json());

// Middleware for authentication
function authenticate(role) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

    const token = authHeader.split(" ")[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
      if (!user || (role && user.type !== role)) {
        return res.status(403).json({ error: "Forbidden" });
      }
      req.user = user;
      next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid token" });
    }
  };
}

// Routes

// User registration
app.post("/register", async (req, res) => {
  const { name, email, password, type } = req.body;

  if (!name || !email || !password || !type) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (!["ALUNO", "PROFESSOR"].includes(type)) {
    return res.status(400).json({ error: "Invalid user type" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword, type },
    });
    res.status(201).json(user);
  } catch (err) {
    res.status(500).json({ error: "Error creating user" });
  }
});

// User login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password" });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: "Error logging in" });
  }
});

// Get all users (Admin only)
app.get("/users", authenticate("ADMINISTRADOR"), async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Error fetching users" });
  }
});

// Create a course (Professor only)
app.post("/courses", authenticate("PROFESSOR"), async (req, res) => {
  const { name, description, category, difficulty } = req.body;

  if (!name || !description || !category || !difficulty) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const course = await prisma.course.create({
      data: {
        name,
        description,
        category,
        difficulty,
        createdById: req.user.id,
      },
    });
    res.status(201).json(course);
  } catch (err) {
    res.status(500).json({ error: "Error creating course" });
  }
});

// Get all courses
app.get("/courses", async (req, res) => {
  try {
    const courses = await prisma.course.findMany();
    res.json(courses);
  } catch (err) {
    res.status(500).json({ error: "Error fetching courses" });
  }
});

// Get course by ID
app.get("/courses/:id", async (req, res) => {
  const courseId = parseInt(req.params.id);

  if (isNaN(courseId)) {
    return res.status(400).json({ error: "Invalid course ID" });
  }

  try {
    const course = await prisma.course.findUnique({ where: { id: courseId } });
    if (!course) return res.status(404).json({ error: "Course not found" });
    res.json(course);
  } catch (err) {
    res.status(500).json({ error: "Error fetching course" });
  }
});

// Update a course (Admin only)
app.put("/courses/:id", authenticate("ADMINISTRADOR"), async (req, res) => {
  const courseId = parseInt(req.params.id);
  const { name, description, category, difficulty } = req.body;

  if (isNaN(courseId)) {
    return res.status(400).json({ error: "Invalid course ID" });
  }

  try {
    const course = await prisma.course.update({
      where: { id: courseId },
      data: { name, description, category, difficulty },
    });
    res.json(course);
  } catch (err) {
    res.status(500).json({ error: "Error updating course" });
  }
});

// Delete a course (Admin only)
app.delete("/courses/:id", authenticate("ADMINISTRADOR"), async (req, res) => {
  const courseId = parseInt(req.params.id);

  if (isNaN(courseId)) {
    return res.status(400).json({ error: "Invalid course ID" });
  }

  try {
    await prisma.course.delete({ where: { id: courseId } });
    res.status(204).end();
  } catch (err) {
    res.status(500).json({ error: "Error deleting course" });
  }
});

// Initialize admin account
async function initializeAdmin() {
  const hashedPassword = await bcrypt.hash("admin123", 10);
  await prisma.user.upsert({
    where: { email: "admin@admin.com" },
    update: {},
    create: {
      name: "Admin",
      email: "admin@admin.com",
      password: hashedPassword,
      type: "ADMINISTRADOR",
    },
  });
}

// Start the server
initializeAdmin().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});