const c = [
	() => import("../../../src/routes/__layout.svelte"),
	() => import("../components/error.svelte"),
	() => import("../../../src/routes/index.svelte"),
	() => import("../../../src/routes/models/Comment.svelte"),
	() => import("../../../src/routes/models/Token.svelte"),
	() => import("../../../src/routes/models/Post.svelte"),
	() => import("../../../src/routes/models/User.svelte")
];

const d = decodeURIComponent;

export const routes = [
	// src/routes/index.svelte
	[/^\/$/, [c[0], c[2]], [c[1]]],

	// src/routes/models/Comment.svelte
	[/^\/models\/Comment\/?$/, [c[0], c[3]], [c[1]]],

	// src/routes/models/Token.svelte
	[/^\/models\/Token\/?$/, [c[0], c[4]], [c[1]]],

	// src/routes/models/Post.svelte
	[/^\/models\/Post\/?$/, [c[0], c[5]], [c[1]]],

	// src/routes/models/User.svelte
	[/^\/models\/User\/?$/, [c[0], c[6]], [c[1]]]
];

export const fallback = [c[0](), c[1]()];