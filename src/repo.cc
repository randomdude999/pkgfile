#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "macro.hh"
#include "repo.hh"

repo_t::~repo_t() {
  if (tmpfile.fd >= 0) {
    close(tmpfile.fd);
  }
}

static size_t strtrim(char *str) {
  char *left = str, *right;

  if (!str || *str == '\0') {
    return 0;
  }

  while (isspace((unsigned char)*left)) {
    left++;
  }
  if (left != str) {
    memmove(str, left, (strlen(left) + 1));
    left = str;
  }

  if (*str == '\0') {
    return 0;
  }

  right = strchr(str, '\0') - 1;
  while (isspace((unsigned char)*right)) {
    right--;
  }
  *++right = '\0';

  return right - left;
}

static char *split_keyval(char *line, const char *sep) {
  strsep(&line, sep);
  return line;
}

static int parse_one_file(const char *, char **, struct repovec_t *);

static int parse_include(const char *include, char **section,
                         struct repovec_t *repos) {
  glob_t globbuf;

  if (glob(include, GLOB_NOCHECK, NULL, &globbuf) != 0) {
    fprintf(stderr, "warning: globbing failed on '%s': out of memory\n",
            include);
    return -ENOMEM;
  }

  for (size_t i = 0; i < globbuf.gl_pathc; ++i) {
    parse_one_file(globbuf.gl_pathv[i], section, repos);
  }

  globfree(&globbuf);

  return 0;
}

static int parse_one_file(const char *filename, char **section,
                          struct repovec_t *repos) {
  FILE *fp;
  char *ptr;
  char line[4096];
  const char *const server = "Server";
  const char *const include = "Include";
  const char *const architecture = "Architecture";
  int in_options = 0, r = 0, lineno = 0;

  fp = fopen(filename, "r");
  if (!fp) {
    fprintf(stderr, "error: failed to open %s: %s\n", filename,
            strerror(errno));
    return -errno;
  }

  while (fgets(line, sizeof(line), fp)) {
    size_t len;
    ++lineno;

    /* remove comments */
    ptr = strchr(line, '#');
    if (ptr) {
      *ptr = '\0';
    }

    len = strtrim(line);
    if (len == 0) {
      continue;
    }

    /* found a section header */
    if (line[0] == '[' && line[len - 1] == ']') {
      free(*section);
      *section = strndup(&line[1], len - 2);
      in_options = len - 2 == 7 && memcmp(*section, "options", 7) == 0;
      if (!in_options) {
        repos->repos.emplace_back(*section);
      }
    }

    if (memchr(line, '=', len)) {
      char *key = line, *val = split_keyval(line, "=");
      size_t keysz = strtrim(key), valsz = strtrim(val);

      if (keysz == strlen(server) && memcmp(key, server, keysz) == 0) {
        if (*section == NULL) {
          fprintf(
              stderr,
              "error: failed to parse %s on line %d: found 'Server' directive "
              "outside of a section\n",
              filename, lineno);
          continue;
        }
        if (in_options) {
          fprintf(
              stderr,
              "error: failed to parse %s on line %d: found 'Server' directive "
              "in options section\n",
              filename, lineno);
          continue;
        }

        repos->repos.back().servers.push_back(val);
      } else if (keysz == strlen(include) && memcmp(key, include, keysz) == 0) {
        parse_include(val, section, repos);
      } else if (in_options && keysz == strlen(architecture) &&
                 memcmp(key, architecture, keysz) == 0) {
        if (valsz != 4 || memcmp(val, "auto", 4) != 0) {
          repos->architecture.assign(val, valsz);
        }
      }
    }
  }

  fclose(fp);

  return r;
}

int load_repos_from_file(const char *filename, struct repovec_t *repos) {
  _cleanup_free_ char *section = NULL;
  int k;

  k = parse_one_file(filename, &section, repos);
  if (k < 0) {
    return k;
  }

  return 0;
}

/* vim: set ts=2 sw=2 et: */
