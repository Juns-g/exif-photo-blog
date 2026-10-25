import { verifyImportRequest } from '@/import/auth';
import { CURRENT_STORAGE } from '@/app/config';
import {
  baseUrlForStorage,
  generateFileNameWithId,
  getSignedUrlForKey,
} from '@/platforms/storage';
import { z } from 'zod';

export const runtime = 'nodejs';

const schema = z.object({
  extension: z.enum(['jpg', 'jpeg', 'png', 'heic', 'webp']),
});

export async function POST(request: Request) {
  const rawBody = Buffer.from(await request.arrayBuffer());
  if (!verifyImportRequest(request, rawBody, process.env.IMPORT_PUBLIC_KEY)) {
    return new Response('Unauthorized', { status: 401 });
  }

  let json: unknown;
  try {
    json = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return new Response('Invalid JSON', { status: 400 });
  }
  const result = schema.safeParse(json);
  if (!result.success) {
    return new Response('Invalid extension', { status: 400 });
  }

  const key = `${generateFileNameWithId('upload')}.${result.data.extension}`;
  const putUrl = await getSignedUrlForKey(key, 'PUT');
  return Response.json({
    uploadUrl: `${baseUrlForStorage(CURRENT_STORAGE)}/${key}`,
    putUrl,
  }, { headers: { 'Cache-Control': 'no-store' } });
}
