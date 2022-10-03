;;; export.el --- export settings -*- lexical-binding: t; -*-
;;; Code:

(add-to-list 'org-latex-classes
             '("ctexart" "\\documentclass{ctexart}"
               ("\\section{%s}" . "\\section*{%s}")
               ("\\subsection{%s}" . "\\subsection*{%s}")
               ("\\paragraph{%s}" . "\\paragraph*{%s}")))
(setq org-latex-minted-options
      '(("breaklines" . "true")
        ("linenos" . "true")
        ("frame" . "lines")
        ))
;;; export.el ends here
