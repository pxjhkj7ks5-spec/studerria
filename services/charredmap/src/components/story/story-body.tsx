import ReactMarkdown from "react-markdown";

type StoryBodyProps = {
  body: string;
};

export function StoryBody({ body }: StoryBodyProps) {
  return (
    <div className="space-y-4 text-[15px] leading-7 text-[#dedfe3] md:text-base">
      <ReactMarkdown
        components={{
          p: ({ children }) => <p className="text-balance">{children}</p>,
          h2: ({ children }) => (
            <h2 className="font-display text-2xl text-white md:text-3xl">{children}</h2>
          ),
          h3: ({ children }) => (
            <h3 className="font-display text-xl text-white md:text-2xl">{children}</h3>
          ),
          ul: ({ children }) => <ul className="list-disc space-y-2 pl-5">{children}</ul>,
          ol: ({ children }) => <ol className="list-decimal space-y-2 pl-5">{children}</ol>,
          blockquote: ({ children }) => (
            <blockquote className="border-l border-[--accent-orange]/70 pl-4 text-white">
              {children}
            </blockquote>
          ),
        }}
      >
        {body}
      </ReactMarkdown>
    </div>
  );
}
