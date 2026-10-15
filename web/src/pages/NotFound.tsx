import { A } from "@solidjs/router";
import { Button } from "~/components/ui";

export default function NotFound() {
  return (
    <div class="empty-state min-h-[60vh]">
      <h2 class="mb-2 text-[3rem] font-bold">
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
