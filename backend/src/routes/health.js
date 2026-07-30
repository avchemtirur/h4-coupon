import { Router } from 'express';

const router = Router();

router.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: 'H4 ERP Backend is running',
    time: new Date().toISOString(),
  });
});

export default router;