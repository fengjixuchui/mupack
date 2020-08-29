#include "../logger.h"
#include "../stdafx.h"
#include "powapack.h"
using namespace pe_bliss;

void rebuild_resources(pe_base *image, resource_directory *new_root_dir) {

    // Get original file resources (root directory)
    resource_directory root_dir = get_resources(*image);
    // Wrap original and new resource directory
    // using helper classes
    pe_resource_viewer res(root_dir);
    pe_resource_manager new_res(*new_root_dir);

    try {
      // List all named icon groups
      // and icon groups with ID
      pe_resource_viewer::resource_id_list icon_id_list(
          res.list_resource_ids(pe_resource_viewer::resource_icon_group));
      pe_resource_viewer::resource_name_list icon_name_list(
          res.list_resource_names(pe_resource_viewer::resource_icon_group));
      // Named resources are always placed first, so let's check if they exist
      if (!icon_name_list.empty()) {
        // Get first icon for first language (by index 0)
        // If we would have to list languages for specific icon, we could call
        // list_resource_languages If we would have to get an icon for specific
        // language, we could call get_icon_by_name (overload with language
        // parameter) Add an icon group to a new resource directory
        resource_cursor_icon_writer(new_res).add_icon(
            resource_cursor_icon_reader(res).get_icon_by_name(
                icon_name_list[0]),
            icon_name_list[0],
            res.list_resource_languages(pe_resource_viewer::resource_icon_group,
                                        icon_name_list[0])
                .at(0));
      } else if (!icon_id_list.empty()) // If there aren't any named icon
                                        // groups, but groups with ID exist
      {
        // Get first icon for first language (by index 0)
        // If we would have to list languages for specified icon, we could call
        // list_resource_languages If we would have to get icon for certain
        // language, we could call get_icon_by_id_lang Add an icon group to a new
        // resource directory
        resource_cursor_icon_writer(new_res).add_icon(
            resource_cursor_icon_reader(res).get_icon_by_id(icon_id_list[0]),
            icon_id_list[0],
            res.list_resource_languages(pe_resource_viewer::resource_icon_group,
                                        icon_id_list[0])
                .at(0));
      }
    } catch (const pe_exception &) {
      // If there is any issue with resources, for example, missing icons,
      // do nothing
    }

    try {
      // List manifests with ID
      pe_resource_viewer::resource_id_list manifest_id_list(
          res.list_resource_ids(pe_resource_viewer::resource_manifest));
      if (!manifest_id_list.empty()) // If manifest exists
      {
        // Get first manifest for first language (by index 0)
        // Add manifest to a new resource group
        new_res.add_resource(
            res.get_resource_data_by_id(pe_resource_viewer::resource_manifest,
                                        manifest_id_list[0])
                .get_data(),
            pe_resource_viewer::resource_manifest, manifest_id_list[0],
            res.list_resource_languages(pe_resource_viewer::resource_manifest,
                                        manifest_id_list[0])
                .at(0));
      }
    } catch (const pe_exception &) {
      // If there is any resource error,
      // do nothing
    }

    try {
      // Get list of version information structures with ID
      pe_resource_viewer::resource_id_list version_info_id_list(
          res.list_resource_ids(pe_resource_viewer::resource_version));
      if (!version_info_id_list.empty()) // If version information exists
      {
        // Get first version information structure for first language (by index
        // 0) Add version information to a new resource directory
        new_res.add_resource(
            res.get_resource_data_by_id(pe_resource_viewer::resource_version,
                                        version_info_id_list[0])
                .get_data(),
            pe_resource_viewer::resource_version, version_info_id_list[0],
            res.list_resource_languages(pe_resource_viewer::resource_version,
                                        version_info_id_list[0])
                .at(0));
      }
    } catch (const pe_exception &) {
      // If there is any resource error,
      // do nothing
    }
}