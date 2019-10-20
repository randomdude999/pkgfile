#include "pkgfile.hh"

#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>

#include <filesystem>
#include <future>
#include <map>
#include <optional>
#include <sstream>
#include <vector>

#include "archive_io.hh"
#include "compress.hh"
#include "filter.hh"
#include "result.hh"
#include "update.hh"

static struct config_t config;

static const char* filtermethods[2] = {"glob", "regex"};

namespace fs = std::filesystem;

using RepoMap = std::map<std::string, fs::path>;

namespace {

std::string FormatSearchResult(const std::string& repo, const Package& pkg) {
  std::stringstream ss;

  if (config.verbose) {
    ss << repo << '/' << pkg.name << ' ' << pkg.version;
    return ss.str();
  }

  if (config.quiet) {
    return std::string(pkg.name);
  }

  ss << repo << '/' << pkg.name;
  return ss.str();
}

int SearchMetafile(const std::string& repo,
                   const pkgfile::filter::Filter& filter, const Package& pkg,
                   pkgfile::Result* result, pkgfile::ArchiveReader* reader) {
  std::string line;
  while (reader->GetLine(&line) == ARCHIVE_OK) {
    if (!filter.Matches(line)) {
      continue;
    }

    result->Add(FormatSearchResult(repo, pkg),
                config.verbose ? line : std::string());

    if (!config.verbose) {
      return 0;
    }
  }

  return 0;
}

int ListMetafile(const std::string& repo, const pkgfile::filter::Filter& filter,
                 const Package& pkg, pkgfile::Result* result,
                 pkgfile::ArchiveReader* reader) {
  if (!filter.Matches(pkg.name)) {
    return 0;
  }

  pkgfile::filter::Bin is_bin;
  std::string line;
  while (reader->GetLine(&line) == ARCHIVE_OK) {
    if (config.binaries && !is_bin.Matches(line)) {
      continue;
    }

    std::string out;
    if (config.quiet) {
      out.assign(line);
    } else {
      std::stringstream ss;
      ss << repo << '/' << pkg.name;
      out = ss.str();
    }
    result->Add(out, config.quiet ? std::string() : line);
  }

  // When we encounter a match with fixed string matching, we know we're done.
  // However, for other filter methods, we can't be sure that our pattern won't
  // produce further matches, so we signal our caller to continue.
  return config.filterby == FILTER_EXACT ? -1 : 0;
}

bool ParsePkgname(Package* pkg, std::string_view entryname) {
  auto pkgrel = entryname.rfind('-');
  if (pkgrel == std::string_view::npos) {
    return false;
  }

  auto pkgver = entryname.substr(0, pkgrel).rfind('-');
  if (pkgver == std::string_view::npos) {
    return false;
  }

  pkg->name = entryname.substr(0, pkgver);
  pkg->version = entryname.substr(pkgver + 1);

  return true;
}

std::optional<pkgfile::Result> ProcessRepo(
    const fs::path repo, const pkgfile::ArchiveEntryCallback& entry_callback,
    const pkgfile::filter::Filter& filter) {
  auto fd = pkgfile::ReadOnlyFile::Open(repo);
  if (fd == nullptr) {
    if (errno != ENOENT) {
      fprintf(stderr, "failed to open %s for reading: %s\n", repo.c_str(),
              strerror(errno));
    }
    return std::nullopt;
  }

  const char* err;
  auto read_archive = pkgfile::ReadArchive::New(fd->fd(), &err);
  if (read_archive == nullptr) {
    fprintf(stderr, "failed to create new archive for reading: %s: %s\n",
            repo.c_str(), err);
    return std::nullopt;
  }

  pkgfile::Result result(repo.stem());
  pkgfile::ArchiveReader reader(read_archive->read_archive());

  archive_entry* e;
  while (reader.Next(&e) == ARCHIVE_OK) {
    const char* entryname = archive_entry_pathname(e);

    Package pkg;
    if (!ParsePkgname(&pkg, entryname)) {
      fprintf(stderr, "error parsing pkgname from: %s\n", entryname);
      continue;
    }

    if (entry_callback(repo.stem(), filter, pkg, &result, &reader) < 0) {
      break;
    }
  }

  return result;
}

void Usage(void) {
  fputs("pkgfile " PACKAGE_VERSION "\nUsage: pkgfile [options] target\n\n",
        stdout);
  fputs(
      " Operations:\n"
      "  -l, --list              list contents of a package\n"
      "  -s, --search            search for packages containing the target "
      "(default)\n"
      "  -u, --update            update repo files lists\n\n",
      stdout);
  fputs(
      " Matching:\n"
      "  -b, --binaries          return only files contained in a bin dir\n"
      "  -d, --directories       match directories in searches\n"
      "  -g, --glob              enable matching with glob characters\n"
      "  -i, --ignorecase        use case insensitive matching\n"
      "  -R, --repo <repo>       search a singular repo\n"
      "  -r, --regex             enable matching with regular expressions\n\n",
      stdout);
  fputs(
      " Output:\n"
      "  -q, --quiet             output less when listing\n"
      "  -v, --verbose           output more\n"
      "  -w, --raw               disable output justification\n"
      "  -0, --null              null terminate output\n\n",
      stdout);
  fputs(
      " Downloading:\n"
      "  -z, --compress[=type]   compress downloaded repos\n\n",
      stdout);
  fputs(
      " General:\n"
      "  -C, --config <file>     use an alternate config (default: "
      "/etc/pacman.conf)\n"
      "  -D, --cachedir <dir>    use an alternate cachedir "
      "(default: " DEFAULT_CACHEPATH
      ")\n"
      "  -h, --help              display this help and exit\n"
      "  -V, --version           display the version and exit\n\n",
      stdout);
}

void Version(void) { fputs(PACKAGE_NAME " v" PACKAGE_VERSION "\n", stdout); }

int ParseOpts(int argc, char** argv) {
  static constexpr char kPacmanConfig[] = "/etc/pacman.conf";
  static constexpr char kShortOpts[] = "0bC:D:dghilqR:rsuVvwz::";
  static constexpr struct option kLongOpts[] = {
      {"binaries", no_argument, 0, 'b'},
      {"cachedir", required_argument, 0, 'D'},
      {"compress", optional_argument, 0, 'z'},
      {"config", required_argument, 0, 'C'},
      {"directories", no_argument, 0, 'd'},
      {"glob", no_argument, 0, 'g'},
      {"help", no_argument, 0, 'h'},
      {"ignorecase", no_argument, 0, 'i'},
      {"list", no_argument, 0, 'l'},
      {"quiet", no_argument, 0, 'q'},
      {"repo", required_argument, 0, 'R'},
      {"regex", no_argument, 0, 'r'},
      {"search", no_argument, 0, 's'},
      {"update", no_argument, 0, 'u'},
      {"version", no_argument, 0, 'V'},
      {"verbose", no_argument, 0, 'v'},
      {"raw", no_argument, 0, 'w'},
      {"null", no_argument, 0, '0'},
      {0, 0, 0, 0}};

  // defaults
  config.filefunc = SearchMetafile;
  config.eol = '\n';
  config.cfgfile = kPacmanConfig;
  config.cachedir = DEFAULT_CACHEPATH;
  config.mode = MODE_SEARCH;

  for (;;) {
    int opt = getopt_long(argc, argv, kShortOpts, kLongOpts, nullptr);
    if (opt < 0) {
      break;
    }
    switch (opt) {
      case '0':
        config.eol = '\0';
        break;
      case 'b':
        config.binaries = true;
        break;
      case 'C':
        config.cfgfile = optarg;
        break;
      case 'D':
        config.cachedir = optarg;
        break;
      case 'd':
        config.directories = true;
        break;
      case 'g':
        if (config.filterby != FILTER_EXACT) {
          fprintf(stderr, "error: --glob cannot be used with --%s option\n",
                  filtermethods[config.filterby]);
          return 1;
        }
        config.filterby = FILTER_GLOB;
        break;
      case 'h':
        Usage();
        exit(EXIT_SUCCESS);
      case 'i':
        config.icase = true;
        break;
      case 'l':
        config.mode = MODE_LIST;
        config.filefunc = ListMetafile;
        break;
      case 'q':
        config.quiet = true;
        break;
      case 'R':
        config.targetrepo = optarg;
        break;
      case 'r':
        if (config.filterby != FILTER_EXACT) {
          fprintf(stderr, "error: --regex cannot be used with --%s option\n",
                  filtermethods[config.filterby]);
          return 1;
        }
        config.filterby = FILTER_REGEX;
        break;
      case 's':
        config.mode = MODE_SEARCH;
        config.filefunc = SearchMetafile;
        break;
      case 'u':
        if (config.mode & MODE_UPDATE) {
          config.mode = MODE_UPDATE_FORCE;
        } else {
          config.mode = MODE_UPDATE_ASNEEDED;
        }
        break;
      case 'V':
        Version();
        exit(EXIT_SUCCESS);
      case 'v':
        config.verbose = true;
        break;
      case 'w':
        config.raw = true;
        break;
      case 'z':
        if (optarg != nullptr) {
          auto compress = pkgfile::ValidateCompression(optarg);
          if (compress == std::nullopt) {
            fprintf(stderr, "error: invalid compression option %s\n", optarg);
            return 1;
          }
          config.compress = compress.value();
        } else {
          config.compress = ARCHIVE_FILTER_GZIP;
        }
        break;
      default:
        return 1;
    }
  }

  return 0;
}

int SearchSingleRepo(const RepoMap& repos,
                     const pkgfile::ArchiveEntryCallback& entry_callback,
                     const pkgfile::filter::Filter& filter,
                     std::string_view searchstring) {
  std::string wanted_repo;
  if (config.targetrepo) {
    wanted_repo = config.targetrepo;
  } else {
    wanted_repo = searchstring.substr(0, searchstring.find('/'));
  }

  auto iter = repos.find(wanted_repo);
  if (iter == repos.end()) {
    fprintf(stderr, "error: repo not available: %s\n", wanted_repo.c_str());
  }

  auto result = ProcessRepo(iter->second, entry_callback, filter);
  if (!result.has_value() || result->Empty()) {
    return 1;
  }

  result->Print(config.raw ? 0 : result->MaxPrefixlen(), config.eol);
  return 0;
}

int SearchAllRepos(const RepoMap& repos,
                   const pkgfile::ArchiveEntryCallback& entry_callback,
                   const pkgfile::filter::Filter& filter) {
  std::vector<std::future<std::optional<pkgfile::Result>>> futures;
  for (const auto& repo : repos) {
    futures.push_back(std::async(std::launch::async, [&] {
      return ProcessRepo(repo.second, entry_callback, filter);
    }));
  }

  std::vector<pkgfile::Result> results;
  for (auto& fu : futures) {
    auto result = fu.get();
    if (result.has_value() && !result->Empty()) {
      results.emplace_back(std::move(result.value()));
    }
  }

  if (results.empty()) {
    return 1;
  }

  size_t prefixlen = config.raw ? 0 : MaxPrefixlen(results);
  for (auto& result : results) {
    result.Print(prefixlen, config.eol);
  }

  return 0;
}

std::unique_ptr<pkgfile::filter::Filter> BuildFilterFromOptions(
    const config_t& config, const std::string& match) {
  std::unique_ptr<pkgfile::filter::Filter> filter;

  bool case_sensitive = !config.icase;

  switch (config.filterby) {
    case FILTER_EXACT:
      if (config.mode == MODE_SEARCH) {
        if (match.find('/') != std::string::npos) {
          filter =
              std::make_unique<pkgfile::filter::Exact>(match, case_sensitive);
        } else {
          filter = std::make_unique<pkgfile::filter::Basename>(match,
                                                               case_sensitive);
        }
      } else if (config.mode == MODE_LIST) {
        auto pos = match.find('/');
        if (pos != std::string::npos) {
          filter = std::make_unique<pkgfile::filter::Exact>(
              match.substr(pos + 1), case_sensitive);
        } else {
          filter =
              std::make_unique<pkgfile::filter::Exact>(match, case_sensitive);
        }
      }
      break;
    case FILTER_GLOB:
      filter = std::make_unique<pkgfile::filter::Glob>(match, case_sensitive);
      break;
    case FILTER_REGEX:
      filter = pkgfile::filter::Regex::Compile(match, case_sensitive);
      if (filter == nullptr) {
        return nullptr;
      }
      break;
  }

  if (config.mode == MODE_SEARCH) {
    if (config.binaries) {
      filter = std::make_unique<pkgfile::filter::And>(
          std::make_unique<pkgfile::filter::Bin>(), std::move(filter));
    }

    std::unique_ptr<pkgfile::filter::Filter> dir_filter =
        std::make_unique<pkgfile::filter::Directory>();
    if (!config.directories) {
      dir_filter =
          std::make_unique<pkgfile::filter::Not>(std::move(dir_filter));
    }

    filter = std::make_unique<pkgfile::filter::And>(std::move(dir_filter),
                                                    std::move(filter));
  }

  return filter;
}

RepoMap DiscoverRepos(std::string_view cachedir) {
  RepoMap repos;

  for (const auto& p : fs::directory_iterator(cachedir)) {
    if (!p.is_regular_file() || p.path().extension() != ".files") {
      continue;
    }

    repos.emplace(p.path().stem(), p.path());
  }

  return repos;
}

}  // namespace

int main(int argc, char* argv[]) {
  setlocale(LC_ALL, "");

  if (ParseOpts(argc, argv) != 0) {
    return 2;
  }

  if (config.mode & MODE_UPDATE) {
    return pkgfile::Updater(config.cachedir, config.compress)
        .Update(config.cfgfile, config.mode == MODE_UPDATE_FORCE);
  }

  if (optind == argc) {
    fputs("error: no target specified (use -h for help)\n", stderr);
    return 1;
  }

  auto filter = BuildFilterFromOptions(config, argv[optind]);
  if (filter == nullptr) {
    return 1;
  }

  auto repos = DiscoverRepos(config.cachedir);
  if (repos.empty()) {
    fputs("error: No repo files found. Please run `pkgfiled -o'.\n", stderr);
  }

  // override behavior on $repo/$pkg syntax or --repo
  if ((config.mode == MODE_LIST && strchr(argv[optind], '/')) ||
      config.targetrepo) {
    return SearchSingleRepo(repos, config.filefunc, *filter, argv[optind]);
  }

  return SearchAllRepos(repos, config.filefunc, *filter);
}

// vim: set ts=2 sw=2 et:
