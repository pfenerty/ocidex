import { A } from "@solidjs/router";

export default function NotFound() {
  return (
    <div class="empty-state" style={{ "min-height": "60vh" }}>
      <h2 style={{ "font-size": "3rem", "font-weight": "700", "margin-bottom": "0.5rem" }}>
        404
      </h2>
      <strong>Page not found</strong>
      <p>The page you're looking for doesn't exist or has been moved.</p>
      <A href="/" class="btn btn-primary" style={{ "margin-top": "1.5rem" }}>
        Back to Dashboard
      </A>
    </div>
  );
}
