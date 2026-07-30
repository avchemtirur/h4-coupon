import { Router } from 'express';

const router = Router();

router.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'H4 ERP API v1',
    version: '1.0.0',
  });
});

export default router;