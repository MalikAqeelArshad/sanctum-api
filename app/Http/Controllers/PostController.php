<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;

class PostController extends Controller
{
    use AuthorizesRequests;

    public function index()
    {
        return Post::with('user')->get();
    }

    public function store(Request $request)
    {
        $request->validate([
            'title' => 'required|string',
            'content' => 'required|string',
        ]);

        return $request->user()->posts()->create($request->only('title', 'content'));
    }

    public function show(Post $post)
    {
        $this->authorize('update', $post);
        return $post;
    }

    public function update(Request $request, Post $post)
    {
        $this->authorize('update', $post);
        $post->update($request->only('title', 'content'));
        return $post;
    }

    public function destroy(Post $post)
    {
        $this->authorize('delete', $post);
        $post->delete();
        return response()->noContent();
    }
}