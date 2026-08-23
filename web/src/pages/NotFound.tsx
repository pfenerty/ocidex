import { A } from "@solidjs/router";
import { Button } from "~/components/ui";

export default function NotFound() {
  return (
    <div class="empty-state" style={{ "min-height": "60vh" }}>
      <h2 style={{ "font-size": "3rem", "font-weight": "700", "margin-bottom": "0.5rem" }}>
        404
      </h2>
      <strong>Page not found</strong>
      <p>The page you're looking for doesn't exist or has been moved.</p>
      <Button as={A} href="/" variant="primary" class="mt-6">
        Back to Dashboard
      </Button>
    </div>
  );
}
