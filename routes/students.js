import express from 'express';
import bcrypt from 'bcrypt';
import { prisma } from '../index.js';

const router = express.Router();

const SALT_ROUNDS = 10;

// GET /api/students
router.get('/', async (req, res) => {
  try {
    const students = await prisma.registeredStudent.findMany({
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        department: true,
        year: true,
        enrollmentNumber: true,
        isActive: true,
        createdAt: true
        // Exclude passwordHash from response
      },
      orderBy: { createdAt: 'desc' }
    });
    res.json(students);
  } catch (error) {
    console.error('Error fetching students:', error);
    res.status(500).json({ error: 'Failed to fetch students' });
  }
});

// POST /api/students
router.post('/', async (req, res) => {
  try {
    const { id, name, email, phone, department, year, enrollmentNumber, password } = req.body;
    
    if (!id || !name || !email || !phone || !department || !year || !enrollmentNumber) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Hash password if provided
    let passwordHash = null;
    if (password) {
      passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    }

    const student = await prisma.registeredStudent.create({
      data: { id, name, email, phone, department, year, enrollmentNumber, passwordHash }
    });
    
    // Return without password hash
    const { passwordHash: _, ...studentResponse } = student;
    res.status(201).json(studentResponse);
  } catch (error) {
    console.error('Error creating student:', error);
    if (error.code === 'P2002') {
      res.status(409).json({ error: 'Student with this ID, email, or enrollment number already exists' });
    } else {
      res.status(500).json({ error: 'Failed to create student' });
    }
  }
});

// POST /api/students/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const student = await prisma.registeredStudent.findFirst({
      where: { 
        email,
        isActive: true 
      }
    });

    if (!student) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!student.passwordHash) {
      return res.status(401).json({ error: 'Password not set. Please set your password first.' });
    }

    const isPasswordValid = await bcrypt.compare(password, student.passwordHash);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Return student info without password hash
    const { passwordHash: _, ...studentResponse } = student;
    res.json({ 
      success: true, 
      student: studentResponse 
    });
  } catch (error) {
    console.error('Error during student login:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /api/students/set-password
router.post('/set-password', async (req, res) => {
  try {
    const { email, enrollmentNumber, password } = req.body;
    
    if (!email || !enrollmentNumber || !password) {
      return res.status(400).json({ error: 'Email, enrollment number, and password are required' });
    }

    // Find student by email and enrollment number (for verification)
    const student = await prisma.registeredStudent.findFirst({
      where: { 
        email,
        enrollmentNumber,
        isActive: true 
      }
    });

    if (!student) {
      return res.status(404).json({ error: 'Student not found or credentials do not match' });
    }

    // Hash and save the new password
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    
    await prisma.registeredStudent.update({
      where: { id: student.id },
      data: { passwordHash }
    });

    res.json({ 
      success: true, 
      message: 'Password set successfully' 
    });
  } catch (error) {
    console.error('Error setting password:', error);
    res.status(500).json({ error: 'Failed to set password' });
  }
});

// POST /api/students/change-password
router.post('/change-password', async (req, res) => {
  try {
    const { email, currentPassword, newPassword } = req.body;
    
    if (!email || !currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Email, current password, and new password are required' });
    }

    const student = await prisma.registeredStudent.findFirst({
      where: { 
        email,
        isActive: true 
      }
    });

    if (!student || !student.passwordHash) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, student.passwordHash);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash and save the new password
    const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    
    await prisma.registeredStudent.update({
      where: { id: student.id },
      data: { passwordHash }
    });

    res.json({ 
      success: true, 
      message: 'Password changed successfully' 
    });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// PUT /api/students/:id
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    delete updateData.id; // Remove ID from update data
    delete updateData.passwordHash; // Don't allow password update through this endpoint

    // If password is being updated, hash it
    if (updateData.password) {
      updateData.passwordHash = await bcrypt.hash(updateData.password, SALT_ROUNDS);
      delete updateData.password;
    }

    const student = await prisma.registeredStudent.update({
      where: { id },
      data: updateData
    });

    // Return without password hash
    const { passwordHash: _, ...studentResponse } = student;
    res.json(studentResponse);
  } catch (error) {
    console.error('Error updating student:', error);
    if (error.code === 'P2025') {
      res.status(404).json({ error: 'Student not found' });
    } else {
      res.status(500).json({ error: 'Failed to update student' });
    }
  }
});

// DELETE /api/students/:id
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    await prisma.registeredStudent.delete({
      where: { id }
    });

    res.status(204).send();
  } catch (error) {
    console.error('Error deleting student:', error);
    if (error.code === 'P2025') {
      res.status(404).json({ error: 'Student not found' });
    } else {
      res.status(500).json({ error: 'Failed to delete student' });
    }
  }
});

export default router;
