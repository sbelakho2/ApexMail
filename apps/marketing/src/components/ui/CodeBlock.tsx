'use client';

interface CodeBlockProps {
  code: string;
  language: string;
}

export function CodeBlock({ code, language }: CodeBlockProps) {
  // Simple syntax highlighting
  const highlightCode = (code: string, lang: string): string => {
    let highlighted = code
      // Escape HTML
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    if (lang === 'typescript' || lang === 'javascript') {
      highlighted = highlighted
        // Comments
        .replace(/(\/\/.*)/g, '<span class="code-comment">$1</span>')
        // Strings
        .replace(/(['"`])((?:(?!\1)[^\\]|\\.)*)(\1)/g, '<span class="code-string">$1$2$3</span>')
        // Keywords
        .replace(/\b(const|let|var|function|async|await|return|if|else|for|while|import|from|export|default|class|new|this|try|catch|throw)\b/g, '<span class="code-keyword">$1</span>')
        // Properties/methods after dot
        .replace(/\.(\w+)/g, '.<span class="code-highlight">$1</span>')
        // Numbers
        .replace(/\b(\d+)\b/g, '<span class="text-orange-400">$1</span>');
    } else if (lang === 'bash' || lang === 'shell') {
      highlighted = highlighted
        // Comments
        .replace(/(#.*)/g, '<span class="code-comment">$1</span>')
        // Strings
        .replace(/(['"])((?:(?!\1)[^\\]|\\.)*)(\1)/g, '<span class="code-string">$1$2$3</span>')
        // Commands
        .replace(/^(\w+)/gm, '<span class="code-keyword">$1</span>')
        // Flags
        .replace(/(\s-\w+)/g, '<span class="text-orange-400">$1</span>');
    } else if (lang === 'json') {
      highlighted = highlighted
        // Keys
        .replace(/"([^"]+)":/g, '<span class="code-highlight">"$1"</span>:')
        // String values
        .replace(/: "([^"]*)"/g, ': <span class="code-string">"$1"</span>')
        // Numbers and booleans
        .replace(/: (\d+|true|false|null)/g, ': <span class="text-orange-400">$1</span>');
    }

    return highlighted;
  };

  return (
    <div className="code-block overflow-x-auto">
      <pre className="p-4 text-sm leading-relaxed">
        <code
          className="font-mono"
          dangerouslySetInnerHTML={{
            __html: highlightCode(code, language),
          }}
        />
      </pre>
    </div>
  );
}
