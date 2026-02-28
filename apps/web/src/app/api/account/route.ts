import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';

const API_BASE = process.env.API_BASE_URL || 'http://localhost:3001';

export async function DELETE(request: NextRequest) {
  try {
    const body = await request.json();

    // Get auth token from cookies
    const cookieStore = await cookies();
    const token = cookieStore.get('auth_token')?.value;

    if (!token) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      );
    }

    // Forward request to backend API
    const response = await fetch(`${API_BASE}/v1/account`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        password: body.password,
        confirmation: body.confirmation,
        reason: body.reason,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json(
        { error: data.error || 'Failed to delete account' },
        { status: response.status }
      );
    }

    // Clear auth cookies on successful deletion
    const res = NextResponse.json(data);
    res.cookies.delete('auth_token');
    res.cookies.delete('refresh_token');

    return res;
  } catch (error) {
    console.error('Account deletion error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
